# name: discourse-single-login-shared
# about: Allow only one concurrent login for a specific shared user
# version: 0.2
# authors: Richard

enabled_site_setting :single_login_shared_enabled

after_initialize do
  module ::SingleLoginShared
    def self.shared_username
      (SiteSetting.single_login_shared_username || "").strip
    end

    def self.timeout_hours
      (SiteSetting.single_login_shared_timeout_hours || 3).to_i
    end

    def self.shared_user?(user)
      user && user.username == shared_username
    end

    def self.active_token_exists?(user)
      cutoff = timeout_hours.hours.ago

      UserAuthToken
        .where(user_id: user.id)
        .where("seen_at IS NOT NULL AND seen_at >= ?", cutoff)
        .exists?
    end
  end

  ::SessionController.prepend Module.new {
    def create
      return super unless SiteSetting.single_login_shared_enabled

      login = params[:login] || params[:username] || params.dig(:session, :login)
      user  = login.present? ? User.find_by_username_or_email(login) : nil

      if ::SingleLoginShared.shared_user?(user) &&
         ::SingleLoginShared.active_token_exists?(user)

        render_json_error(
          "Dieser Account ist bereits aktiv eingeloggt. Bitte später erneut versuchen."
        )
        return
      end

      super
    end
  }
end
