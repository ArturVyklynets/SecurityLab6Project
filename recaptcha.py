import requests


class ReCaptcha:
    VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

    def __init__(self, site_key, secret_key):
        self.site_key = site_key
        self.secret_key = secret_key

    def verify(self, response_token, remote_ip=None):
        if not response_token:
            return False, "Підтвердіть, що ви не робот"

        payload = {
            'secret': self.secret_key,
            'response': response_token
        }

        if remote_ip:
            payload['remoteip'] = remote_ip

        try:
            response = requests.post(self.VERIFY_URL, data=payload, timeout=10)
            result = response.json()

            if result.get('success'):
                return True, "OK"
            else:
                errors = result.get('error-codes', [])
                error_messages = {
                    'missing-input-secret': 'Відсутній секретний ключ',
                    'invalid-input-secret': 'Невірний секретний ключ',
                    'missing-input-response': 'Підтвердіть, що ви не робот',
                    'invalid-input-response': 'Невірний токен CAPTCHA',
                    'bad-request': 'Помилка запиту',
                    'timeout-or-duplicate': 'CAPTCHA застаріла, спробуйте ще раз'
                }
                message = error_messages.get(errors[0] if errors else '', 'Помилка перевірки CAPTCHA')
                return False, message

        except requests.RequestException:
            return False, "Помилка з'єднання з сервером CAPTCHA"
