from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer, BadSignature

class RotateKeysSessionInterface(SecureCookieSessionInterface):
    """
    Özel Session Interface: Birden fazla SECRET_KEY desteği sağlar (Key Rotation).
    """
    
    def get_signing_serializer(self, app):
        if not app.secret_key:
            return None
        
        # app.config['SECRET_KEYS'] listesini al (Eğer yoksa tekil secret_key'i liste yap)
        keys = app.config.get('SECRET_KEYS', [])
        if not keys and app.secret_key:
            keys = [app.secret_key]
            
        # URLSafeTimedSerializer secret_key_or_secret_keys parametresini destekler (itsdangerous >= 2.0)
        # Ancak Flask'ın standart uygulamasında bu desteklenmeyebilir, bu yüzden
        # signer_kwargs içine 'secret_key' yerine keys listesini vermeyi deneyebiliriz
        # YA DA en basiti: Serializer'ı kendimiz döndürürüz.
        
        signer_kwargs = dict(
            key_derivation=self.key_derivation,
            digest_method=self.digest_method
        )
        
        return URLSafeTimedSerializer(
            secret_key=keys,
            salt=self.salt,
            serializer=self.serializer,
            signer_kwargs=signer_kwargs
        )
