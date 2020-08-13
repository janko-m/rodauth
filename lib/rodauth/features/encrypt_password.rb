# frozen-string-literal: true

require 'openssl'

module Rodauth
  Feature.define(:encrypt_password_hash, :EncryptPasswordHash) do
    depends :login_password_requirements_base

    auth_value_method :password_hash_encryption_algorithm, "aes-256-gcm"
    auth_value_method :password_hash_encryption_key, nil
    auth_value_method :password_hash_encryption_iv, nil

    auth_methods(
      :encrypt_password_hash,
      :decrypt_password_hash,
      :password_hash_cipher,
    )

    private

    def use_database_authentication_functions?
      false
    end

    def password_hash(password)
      encrypt_password_hash(super)
    end

    def get_password_hash
      decrypt_password_hash(super)
    end

    def encrypt_password_hash(hash)
      cipher = password_hash_cipher
      cipher.encrypt
      cipher.update(hash) + cipher.final
    end

    def decrypt_password_hash(hash)
      cipher = password_hash_cipher
      cipher.decrypt
      cipher.update(hash) + cipher.final
    end

    def password_hash_cipher
      cipher = OpenSSL::Cipher.new(password_hash_encryption_algorithm)
      cipher.key = password_hash_encryption_key
      cipher.iv = password_hash_encryption_iv
    end

    def password_hash_encryption_key
      raise ArgumentError, "password_hash_encryption_key not set"
    end
  end
end
