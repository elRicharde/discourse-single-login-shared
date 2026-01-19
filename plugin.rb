# name: discourse-single-login-shared
# about: Allow only one concurrent login for specific shared users with static max session logout
# version: 1.5
# authors: Richard

enabled_site_setting :single_login_shared_enabled

after_initialize do

  module ::SingleLoginShared
    def self.shared_usernames
      raw = (SiteSetting.single_login_shared_usernames || "").to_s
      list = raw.split(",").map { |s| s.strip }.reject(&:blank?)

      # optionaler Fallback, falls du noch irgendwo das alte Setting hattest
      if list.empty? && SiteSetting.respond_to?(:single_login_shared_username)
        old = (SiteSetting.single_login_shared_username || "").to_s.strip
        list = [old] if old.present?
      end

      list
    end

    def self.shared_user?(user)
      user && shared_usernames.include?(user.username)
    end

    def self.now
      Time.now.to_i
    end

    def self.max_session_seconds
      SiteSetting.single_login_shared_max_session_minutes.to_i * 60
    end

    # Redis keys (pro User)
    def self.active_key(user_id)
      "single_login_shared:active:user:#{user_id}"
    end

    def self.login_started_key(user_id)
      "single_login_shared:login_started:user:#{user_id}"
    end

    def self.active?(user_id)
      Discourse.redis.exists?(active_key(user_id))
    end

    def self.mark_logged_in!(user_id)
      t   = now
      ttl = max_session_seconds

      # Wenn ttl <= 0, setzen wir ohne TTL (aber Setting hat min:1, also normalerweise nie)
      if ttl > 0
        # kleine Reserve, damit es nicht exakt auf die Sekunde race-conditiont
        exp = ttl + 60
        Discourse.redis.setex(active_key(user_id), exp, "1")
        Discourse.redis.setex(login_started_key(user_id), exp, t.to_s)
      else
        Discourse.redis.set(active_key(user_id), "1")
        Discourse.redis.set(login_started_key(user_id), t.to_s)
      end
    end

    def self.clear_all!(user_id)
      Discourse.redis.del(active_key(user_id), login_started_key(user_id))
    end

    def self.force_logout!(user)
      # logout all sessions/tokens for this user
      UserAuthToken.where(user_id: user.id).find_each do |t|
        begin
          t.log_out!(SessionManager.new(nil, nil))
        rescue
          # fallback: token destroy invalidiert ebenfalls
        ensure
          t.destroy!
        end
      end

      clear_all!(user.id)
    end

    def self.should_logout?(user_id)
      started_s = Discourse.redis.get(login_started_key(user_id))
      started   = started_s.to_i

      # Wenn active gesetzt, aber started fehlt -> inkonsistent -> logout/cleanup
      return [:inconsistent, true] if started <= 0

      ttl = max_session_seconds
      return [:ok, false] if ttl <= 0

      if (now - started) > ttl
        return [:max_session, true]
      end

      [:ok, false]
    end

    def self.enforce_timeouts!
      return unless SiteSetting.single_login_shared_enabled

      # Für alle konfigurierten Shared-User prüfen
      shared_usernames.each do |uname|
        user = User.find_by(username: uname)
        next if user.nil?

        uid = user.id
        next unless active?(uid)

        _reason, logout = should_logout?(uid)
        force_logout!(user) if logout
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

  # 3) Scheduled Job: erzwingt Max-Session Logout unabhängig von Requests
  module ::Jobs
    class SingleLoginSharedEnforcer < ::Jobs::Scheduled
      every 1.minute

      def execute(args)
        ::SingleLoginShared.enforce_timeouts!
      end
    end
  end
end
