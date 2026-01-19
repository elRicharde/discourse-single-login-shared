# name: discourse-single-login-shared
# about: Allow only one concurrent login for specific shared users + forced logout + PM cleanup + notify
# version: 1.5
# authors: Richard

enabled_site_setting :single_login_shared_enabled

after_initialize do
  module ::SingleLoginShared
    LOCK_PREFIX = "single_login_shared:lock:user:".freeze

    def self.shared_usernames
      raw = (SiteSetting.single_login_shared_usernames || "").strip
      return [] if raw.empty?

      raw.split(/[,\s;|]+/).map(&:strip).reject(&:empty?)
    end

    def self.timeout_minutes
      (SiteSetting.single_login_shared_timeout_minutes || 180).to_i
    end

    def self.timeout_seconds
      timeout_minutes * 60
    end

    def self.shared_user?(user)
      user && shared_usernames.include?(user.username)
    end

    def self.lock_key(user_id)
      "#{LOCK_PREFIX}#{user_id}"
    end

    def self.lock_value(user_id)
      Discourse.redis.get(lock_key(user_id))
    end

    def self.locked?(user_id)
      Discourse.redis.exists?(lock_key(user_id))
    end

    # value = random token, so scheduled job can confirm it is still the same "login"
    def self.set_lock!(user_id)
      token = SecureRandom.hex(16)
      Discourse.redis.setex(lock_key(user_id), timeout_seconds, token)
      token
    end

    def self.clear_lock!(user_id)
      Discourse.redis.del(lock_key(user_id))
    end

    # --- Forced logout (best effort, without requiring internal files) ---
    def self.force_logout_all_sessions!(user)
      return if user.blank?

      # Try known helpers if present
      if defined?(UserAuthToken) && UserAuthToken.respond_to?(:log_out)
        # Some versions have: UserAuthToken.log_out(user)
        begin
          UserAuthToken.log_out(user)
          return
        rescue
          # fall through
        end
      end

      # Fallback: revoke all auth tokens (works on most modern Discourse)
      if defined?(UserAuthToken)
        UserAuthToken.where(user_id: user.id).update_all(revoked_at: Time.zone.now)
      end

      # Also bump "log out all sessions" marker if available
      if user.respond_to?(:log_out_all_sessions!)
        user.log_out_all_sessions!
      end
    end

    # --- Remove the user from ALL PMs (so they disappear from inbox/sent) ---
    def self.remove_user_from_all_pms!(user)
      return if user.blank?
      return unless defined?(TopicAllowedUser) && defined?(Topic) && defined?(Archetype)

      TopicAllowedUser
        .joins("JOIN topics ON topics.id = topic_allowed_users.topic_id")
        .where(user_id: user.id)
        .where("topics.archetype = ?", Archetype.private_message)
        .delete_all
    end

    # --- Send automation PM from configured sender to group + the shared user ---
    def self.send_logout_pm!(shared_user)
      return if shared_user.blank?
      return unless defined?(PostCreator) && defined?(Archetype)

      sender_username = (SiteSetting.single_login_shared_sender_username || "").strip
      group_name      = (SiteSetting.single_login_shared_group || "").strip

      sender = User.find_by(username: sender_username)
      return if sender.blank?

      targets = []
      targets << group_name unless group_name.empty?
      targets << shared_user.username
      target_usernames = targets.join(",")

      title = "Shared-Login Logout: #{shared_user.username}"
      raw   = "Der Shared-User **#{shared_user.username}** wurde ausgeloggt (Timeout/Logout).\n\nBitte ggf. Folgeprozess starten."

      PostCreator.create!(
        sender,
        title: title,
        raw: raw,
        archetype: Archetype.private_message,
        target_usernames: target_usernames
      )
    end

    # --- One place that performs all “logout side effects” ---
    def self.on_shared_user_logged_out!(user)
      return unless shared_user?(user)

      clear_lock!(user.id)
      force_logout_all_sessions!(user)
      remove_user_from_all_pms!(user)
      send_logout_pm!(user)
    end
  end

  # Sidekiq job that fires when the fixed timeout is reached
  module ::SingleLoginShared
    class ExpireJob < ::Jobs::Base
      def execute(args)
        user_id = args[:user_id].to_i
        token   = args[:token].to_s
        return if user_id <= 0 || token.empty?

        # Only expire if the lock still exists and matches this token
        current = ::SingleLoginShared.lock_value(user_id)
        return if current.blank?
        return unless current == token

        user = User.find_by(id: user_id)
        return if user.blank?

        ::SingleLoginShared.on_shared_user_logged_out!(user)
      end
    end
  end

  # Block login if locked; on successful login set lock AND schedule expiration job.
  ::SessionController.prepend Module.new {
    def create
      return super unless SiteSetting.single_login_shared_enabled

      login = params[:login] || params[:username] || params.dig(:session, :login)
      user  = login.present? ? User.find_by_username_or_email(login) : nil

      if ::SingleLoginShared.shared_user?(user) && ::SingleLoginShared.locked?(user.id)
        return render_json_error(
          I18n.t("login.already_logged_in_single_session"),
          status: 403
        )
      end

      super
    ensure
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        token = ::SingleLoginShared.set_lock!(u.id)

        # schedule fixed expiration (minutes from now)
        Jobs.enqueue_in(
          ::SingleLoginShared.timeout_minutes.minutes,
          ::SingleLoginShared::ExpireJob,
          user_id: u.id,
          token: token
        )
      end
    end

    # Normal user logout via menu
    def destroy
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.on_shared_user_logged_out!(u)
      end
      super
    end
  }

  # Admin "log out" button
  Admin::UsersController.prepend Module.new {
    def log_out
      user_id = params[:user_id].to_i
      u = User.find_by(id: user_id)
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.on_shared_user_logged_out!(u)
      end
      super
    end
  }
end
