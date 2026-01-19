# name: discourse-single-login-shared
# about: Allow only one concurrent login for a specific shared user with hard and idle timeouts
# version: 1.0
# authors: Richard

enabled_site_setting :single_login_shared_enabled

after_initialize do
  module ::SingleLoginShared
    ### ===== Helpers =====

    def self.shared_username
      (SiteSetting.single_login_shared_username || "").strip
    end

    def self.shared_user?(user)
      user && user.username == shared_username
    end

    def self.now
      Time.now.to_i
    end

    ### ===== Redis keys =====

    def self.active_key(user_id)
      "single_login_shared:active:user:#{user_id}"
    end

    def self.login_started_key(user_id)
      "single_login_shared:login_started:user:#{user_id}"
    end

    def self.last_activity_key(user_id)
      "single_login_shared:last_activity:user:#{user_id}"
    end

    ### ===== State =====

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

    def self.clear_all_keys!(user_id)
      Discourse.redis.del(
        active_key(user_id),
        login_started_key(user_id),
        last_activity_key(user_id)
      )
    end

    ### ===== Logout (ECHT, Discourse-intern) =====

    def self.force_logout!(user)
      UserLogout.new(user).log_out
      clear_all_keys!(user.id)
    end

    ### ===== Timeout checks =====

    def self.check_timeouts!(user)
      user_id = user.id
      current = now

      idle_limit =
        SiteSetting.single_login_shared_idle_timeout_minutes.to_i * 60
      max_limit =
        SiteSetting.single_login_shared_max_session_minutes.to_i * 60

      last_activity =
        Discourse.redis.get(last_activity_key(user_id)).to_i
      login_started =
        Discourse.redis.get(login_started_key(user_id)).to_i

      # Idle timeout
      if last_activity > 0 && current - last_activity > idle_limit
        force_logout!(user)
        return
      end

      # Hard max session timeout
      if login_started > 0 && current - login_started > max_limit
        force_logout!(user)
        return
      end
    end
  end

  ### ===== Login block =====

  ::SessionController.prepend Module.new {
    def create
      return super unless SiteSetting.single_login_shared_enabled

      login =
        params[:login] ||
        params[:username] ||
        params.dig(:session, :login)

      user =
        login.present? ? User.find_by_username_or_email(login) : nil

      if ::SingleLoginShared.shared_user?(user) &&
         ::SingleLoginShared.active?(user.id)
        return render_json_error(
          I18n.t("login.already_logged_in_single_session"),
          status: 403
        )
      end

      super
    ensure
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled &&
         ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.mark_logged_in!(u.id)
      end
    end
  }

  ### ===== User logout =====

  ::SessionController.prepend Module.new {
    def destroy
      u = respond_to?(:current_user) ? current_user : nil
      if SiteSetting.single_login_shared_enabled &&
         ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.clear_all_keys!(u.id)
      end
      super
    end
  }

  ### ===== Admin "log out all" =====

  Admin::UsersController.prepend Module.new {
    def log_out
      user_id = params[:user_id].to_i
      u = User.find_by(id: user_id)

      if SiteSetting.single_login_shared_enabled &&
         ::SingleLoginShared.shared_user?(u)
        ::SingleLoginShared.clear_all_keys!(u.id)
      end

      super
    end
  }

  ### ===== Activity hook =====

  DiscourseEvent.on(:current_user) do |user|
    next unless SiteSetting.single_login_shared_enabled
    next unless ::SingleLoginShared.shared_user?(user)

    ::SingleLoginShared.check_timeouts!(user)
    ::SingleLoginShared.touch_activity!(user.id)
  end
end
