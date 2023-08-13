import unittest
from ioc_richer.src.http.request import get_request, post_request, HEADERS, httpx
from unittest.mock import patch


class Testing(unittest.TestCase):
    @patch("httpx.Client")
    def test_get_request(self, mock_client):
        mock_response = unittest.mock.Mock()
        mock_response.text = "Test data"
        mock_response.status_code = 200
        mock_client().__enter__().get.return_value = mock_response

        url = "https://brandefense.io"
        data = get_request(url, HEADERS)

        self.assertEqual(data.text, "Test data")
        self.assertEqual(data.status_code, 200)

    @patch("httpx.Client")
    def test_post_request(self, mock_client2):
        mock_response = unittest.mock.Mock()
        mock_response.text = "success"
        mock_response.status_code = 200
        mock_client2().__enter__().post.return_value = mock_response
        dataj = {"key1": "value1", "key2": "value2"}

        url = "https://brandefense.io"
        response = post_request(url, head=HEADERS, data=dataj)

        self.assertEqual(response.text, "success")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
