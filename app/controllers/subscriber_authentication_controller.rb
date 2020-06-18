class SubscriberAuthenticationController < ApplicationController
  def sign_in
    @address = params[:address]
  end

  def request_sign_in_token
    if params[:address].blank?
      flash.now[:error] = t("subscriber_authentication.sign_in.missing_email")
      flash.now[:error_summary] = "email"
      return render :sign_in
    end

    @address = params.require(:address)
    VerifySubscriberEmailService.call(@address)
  rescue GdsApi::HTTPUnprocessableEntity
    flash.now[:error] = t("subscriber_authentication.sign_in.invalid_email")
    flash.now[:error_summary] = "email"
    render :sign_in
  rescue VerifySubscriberEmailService::RatelimitExceededError
    head :too_many_requests
  end

  def process_sign_in_token
    unless token.valid?
      deauthenticate_subscriber
      flash[:error_summary] = "bad_token"
      return redirect_to :sign_in
    end

    authenticate_subscriber(token.data[:subscriber_id])
    destination = safe_redirect_destination || list_subscriptions_path
    redirect_to destination
  end

  def request_sign_in_oidc
    response = email_alert_api.get_oidc_url(
      destination: process_sign_in_oidc_path,
    )

    redirect_to response["auth_uri"]
  end

  def process_sign_in_oidc
    response = email_alert_api.verify_oidc_response(
      code: params.require(:code),
      nonce: params.require(:state),
      destination: process_sign_in_oidc_path,
    )

    if response["subscriber"]
      authenticate_subscriber(response["subscriber"]["id"])
      redirect_to list_subscriptions_path
    else
      @state = :confirm
      @account_manager = Plek.find("account-manager")
      @user_id = response["user_id"]
    end
  rescue GdsApi::HTTPNotFound
    # user isn't subscribed, but they've managed to log in.
    @state = :missing
  rescue GdsApi::HTTPForbidden
    # the auth code is invalid, this can happen if a URL gets re-used
    @state = :forbidden
  end

private

  def token
    @token ||= AuthToken.new(params.require(:token))
  end

  def authenticate_subscriber(subscriber_id)
    session["authentication"] = {
      "subscriber_id" => subscriber_id,
    }
  end

  def deauthenticate_subscriber
    session["authentication"] = nil
  end

  def safe_redirect_destination
    redirect = token.data[:redirect]
    return nil unless redirect

    parsed = URI.parse(redirect)
    redirect if parsed.relative? && redirect[0] == "/"
  rescue URI::InvalidURIError
    nil
  end
end
