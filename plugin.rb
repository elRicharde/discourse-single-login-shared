# name: discourse-single-login-shared
# about: Allow only one concurrent login for a specific shared user with idle + max session logout
# version: 1.1
# authors: Richard

enabled_site_setting :single_login_shared_enabled

after_initialize do
  require_dependency "user_logout"

  module ::SingleLoginShared
    def self.shared_username
      (SiteSetting.single_login_shared_username || "").strip
    end

    def self.shared_user?(user)
      user && user.username == shared_username
    end

    def self.shared_user
      u = shared_username
      return nil if u.blank?
      User.find_by(username: u)
    end

    def self.now
      Time.now.to_i
    end

    def self.idle_timeout_seconds
      SiteSetting.single_login_shared_idle_timeout_minutes.to_i * 60
    end

    def self.max_session_seconds
      SiteSetting.single_login_shared_max_session_minutes.to_i * 60
    end

    # Redis keys
    def self.active_key(user_id)
      "single_login_shared:active:user:#{user_id}"
    end

    def self.login_started_key(user_id)
      "single_login_shared:login_started:user:#{user_id}"
    end

    def self.last_activity_key(user_id)
      "single_login_shared:last_activity:user:#{user_id}"
    end

    def self.active?(user_id)
      Discourse.redis.exists?(active_key(user_id))
    end

    def self.mark_logged_in!(user_id)
      t = now
      Discourse.redis.set(active_key(user_id), "1")
      Discourse.redis.set(login_started_key(user_id), t)
      Discourse.redis.set(last_activity_key(user_id), t)
    end

    def self.touch_activity!(user_id)
      Discourse.redis.set(last_activity_key(user_id), now)
    end

    def self.clear_all!(user_id)
      Discourse.redis.del(active_key(user_id), login_started_key(user_id), last_activity_key(user_id))
    end

    def self.force_logout!(user)
      # echter Logout: invalidiert Sessions/Tokens wie UI/Admin-Logout
      UserLogout.new(user).log_out
      clear_all!(user.id)
    end

    def self.should_logout?(user_id)
      t = now
      started = Discourse.redis.get(login_started_key(user_id)).to_i
      last = Discourse.redis.get(last_activity_key(user_id)).to_i

      # Wenn Keys fehlen, lieber nicht hart killen — aber active entfernen, falls inkonsistent
      if started <= 0
        return [:inconsistent, true]
      end

      # Max session (hart)
      if max_session_seconds > 0 && (t - started) > max_session_seconds
        return [:max_session, true]
      end

      # Idle (seit letztem Request)
      if last > 0 && idle_timeout_seconds > 0 && (t - last) > idle_timeout_seconds
        return [:idle, true]
      end

      [:ok, false]
    end

    def self.enforce_timeouts!
      return unless SiteSetting.single_login_shared_enabled

      user = shared_user
      return if user.nil?

      uid = user.id
      return unless active?(uid)

      reason, logout = should_logout?(uid)

      if logout
        # Inconsistency: active gesetzt aber timestamps fehlen -> Sessions beenden und sauber aufräumen
        force_logout!(user)
      end
    end
  end

  # 1) Login blocken + nach erfolgreichem Login markieren
  ::SessionController.prepend Module.new {
    def create
      return super unless SiteSetting.single_login_shared_enabled

      login = params[:login] || params[:username] || params.dig(:session, :login)
      user  = login.present? ? User.find_by_username_or_email(login) : nil

      if ::SingleLoginShared.shared_user?(user) && ::SingleLoginShared.active?(user.id)
        # Wichtig: Discourse Login-UI zeigt das zuverlässig an:
        render json: { error: I18n.t("login.already_logged_in_single_session") }, status: 200
        return
      end

      super
    ensure
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.mark_logged_in!(u.id)
      end
    end

    # normaler Logout
    def destroy
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.clear_all!(u.id)
      end
      super
    end
  }

  # 2) Admin-Logout (Log out all sessions)
  Admin::UsersController.prepend Module.new {
    def log_out
      user_id = params[:user_id].to_i
      u = User.find_by(id: user_id)

      if SiteSetting.single_login_shared_enabled && ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.clear_all!(u.id)
      end

      super
    end
  }

  # 3) Bei jedem Request: Activity timestamp updaten (nur Shared User)
  DiscourseEvent.on(:current_user) do |user|
    next unless SiteSetting.single_login_shared_enabled
    next unless ::SingleLoginShared.shared_user?(user)

    ::SingleLoginShared.touch_activity!(user.id)
  end

  # 4) Scheduled Job: erzwingt Idle/Max logout unabhängig von Requests
  module ::Jobs
    class SingleLoginSharedEnforcer < ::Jobs::Scheduled
      every 1.minute

      def execute(args)
        ::SingleLoginShared.enforce_timeouts!
      end
    end
  end
end
