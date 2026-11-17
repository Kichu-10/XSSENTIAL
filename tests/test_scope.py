import unittest
from unittest.mock import Mock

try:
    from XSSential.scope import UnsafeTargetError, safe_request, validate_loopback_url
except ModuleNotFoundError:
    from scope import UnsafeTargetError, safe_request, validate_loopback_url


class LoopbackScopeTests(unittest.TestCase):
    def test_accepts_localhost_and_loopback_ip_literals(self):
        for url in (
            "http://localhost:8000/",
            "http://127.0.0.1:8000/",
            "http://[::1]:8000/",
        ):
            with self.subTest(url=url):
                self.assertEqual(validate_loopback_url(url), url)

    def test_rejects_non_loopback_hosts_and_credentials(self):
        for url in (
            "https://example.com/",
            "http://localhost.example.com/",
            "http://user:pass@localhost/",
            "http://192.0.2.1/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(UnsafeTargetError):
                    validate_loopback_url(url)

    def test_rejects_external_redirect_without_following_it(self):
        session = Mock()
        response = Mock(
            status_code=302,
            headers={"Location": "https://example.com/"},
            url="http://127.0.0.1:8000/",
        )
        session.request.return_value = response
        origin = ("http", "127.0.0.1", 8000)

        with self.assertRaises(UnsafeTargetError):
            safe_request(
                session,
                "GET",
                "http://127.0.0.1:8000/",
                allowed_origin=origin,
            )

        session.request.assert_called_once()
        session.request.assert_called_once_with(
            "GET",
            "http://127.0.0.1:8000/",
            allow_redirects=False,
        )
        response.close.assert_called_once()

    def test_rejects_redirect_to_a_different_local_origin(self):
        session = Mock()
        response = Mock(
            status_code=302,
            headers={"Location": "http://localhost:8001/"},
            url="http://localhost:8000/",
        )
        session.request.return_value = response

        with self.assertRaises(UnsafeTargetError):
            safe_request(
                session,
                "GET",
                "http://localhost:8000/",
                allowed_origin=("http", "localhost", 8000),
            )

        session.request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
