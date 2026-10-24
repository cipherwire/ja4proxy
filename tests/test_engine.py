import asyncio
import json
import unittest

from ja4proxy.engine.bridge import NativeEngine


class TestNativeEngine(unittest.TestCase):
    def setUp(self):
        self.engine = NativeEngine.get_instance()

    def test_live_handshake_chrome(self):
        async def _run():
            return await self.engine.request(
                method="GET",
                url="https://tls.peet.ws/api/all",
                profile="chrome_133",
                timeout_seconds=15,
            )

        res = asyncio.run(_run())
        self.assertEqual(res["status"], 200)
        self.assertTrue(len(res["body"]) > 0)
        data = json.loads(res["body"].decode("utf-8"))
        self.assertIn("t13", data.get("tls", {}).get("ja4", ""))

    def test_live_post_httpbin(self):
        async def _run():
            payload = json.dumps({"hello": "world", "status": "active"}).encode()
            return await self.engine.request(
                method="POST",
                url="https://httpbin.org/anything",
                headers={"Content-Type": "application/json"},
                body=payload,
                profile="chrome_133",
                timeout_seconds=15,
            )

        res = asyncio.run(_run())
        self.assertEqual(res["status"], 200)
        data = json.loads(res["body"].decode("utf-8"))
        self.assertEqual(data.get("json"), {"hello": "world", "status": "active"})


if __name__ == "__main__":
    unittest.main()
