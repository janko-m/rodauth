# frozen-string-literal: true

module Rodauth
  Feature.define(:password_pepper, :PasswordPepper) do
    auth_value_method :password_pepper, nil

    def password_hash_match?(hash, password)
      password_peppers.any? { |pepper| super(hash, password + pepper) }
    end

    def password_hash(password, salt=nil)
      super(password + password_peppers.first, salt)
    end

    private

    def use_database_authentication_functions?
      false
    end

    def password_peppers
      Array(password_pepper) + [""]
    end
  end
end
