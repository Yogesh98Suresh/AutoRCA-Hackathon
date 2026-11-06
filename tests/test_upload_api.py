import unittest
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4
from unittest.mock import patch

from fastapi import HTTPException

from backend import main
from asgi_client import request


@contextmanager
def upload_data_dir():
    path = Path(__file__).resolve().parent / f"upload-test-{uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        for child in path.iterdir():
            if child.is_file() or child.is_symlink():
                child.unlink()
            else:
                raise AssertionError("Unexpected nested path in upload test directory.")
        path.rmdir()


def multipart_body(filename: str, content: bytes, boundary: str = "AutoRCA-test-boundary") -> tuple[bytes, str]:
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: text/plain\r\n\r\n"
    ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("ascii")
    return body, f"multipart/form-data; boundary={boundary}"


class UploadAPITests(unittest.TestCase):
    def upload(self, directory: Path, filename: str = "incident.log", content: bytes = b"2026-11-01 10:00:00 ERROR api database timeout\n"):
        body, content_type = multipart_body(filename, content)
        with patch.object(main, "DATA_DIR", directory):
            return request(main.app, "POST", "/upload", body, content_type)

    def test_valid_upload_uses_generated_name_analyzes_and_supports_investigation(self):
        with upload_data_dir() as directory:
            status, result = self.upload(directory, "local sample.log")
            self.assertEqual(status, 201)
            self.assertRegex(result["filename"], r"^autorca-upload-[0-9a-f]{32}\.log$")
            self.assertEqual(result["original_filename"], "local sample.log")
            self.assertEqual(result["report"]["incidents"][0]["service"], "api")
            stored_path = directory / result["filename"]
            self.assertTrue(stored_path.is_file())
            with patch.object(main, "DATA_DIR", directory):
                status, investigation = request(main.app, "POST", "/investigations", {
                    "filename": result["filename"], "service": "api",
                })
            self.assertEqual(status, 201)
            self.assertEqual(investigation["filename"], result["filename"])

    def test_rejects_extension_path_traversal_empty_invalid_utf8_and_oversize(self):
        with upload_data_dir() as directory:
            for name, payload, expected_status in (
                ("incident.txt", b"log", 400),
                (r"..\..\outside.log", b"log", 400),
                ("empty.log", b"", 400),
                ("binary.log", b"\xff\xfe", 400),
            ):
                with self.subTest(name=name):
                    status, response = self.upload(directory, name, payload)
                    self.assertEqual(status, expected_status, response)
            with patch.object(main.log_analyzer, "MAX_LOG_FILE_BYTES", 8):
                status, response = self.upload(directory, "large.log", b"x" * 9)
            self.assertEqual(status, 413)
            self.assertIn("AUTORCA_MAX_LOG_BYTES", response["detail"])
            with patch.object(main.log_analyzer, "MAX_LOG_FILE_BYTES", 8):
                status, response = self.upload(directory, "huge.log", b"x" * (70 * 1024))
            self.assertEqual(status, 413)
            self.assertIn("size limit", response["detail"].lower())
            self.assertEqual(list(directory.iterdir()), [])

    def test_bad_multipart_filename_does_not_create_a_file(self):
        with upload_data_dir() as directory:
            for name in ("", "bad\nname.log", "a" * 256 + ".log"):
                with self.subTest(name=name):
                    status, _ = self.upload(directory, name)
                    self.assertEqual(status, 400)
            self.assertEqual(list(directory.iterdir()), [])

    def test_data_directory_must_remain_inside_project(self):
        with patch.object(main, "DATA_DIR", Path("C:/Windows")):
            with self.assertRaises(HTTPException) as error:
                main.list_log_files()
        self.assertEqual(error.exception.status_code, 500)

    def test_retention_removes_only_old_autorca_generated_uploads(self):
        with upload_data_dir() as directory:
            old_generated = directory / ("autorca-upload-" + "a" * 32 + ".log")
            unrelated = directory / "operator.log"
            sample = directory / "sample.log"
            old_generated.write_text("old\n", encoding="utf-8")
            unrelated.write_text("keep\n", encoding="utf-8")
            sample.write_text("keep\n", encoding="utf-8")
            with patch.object(main, "MAX_RETAINED_UPLOADS", 1):
                status, result = self.upload(directory)
            self.assertEqual(status, 201)
            self.assertFalse(old_generated.exists())
            self.assertTrue(unrelated.exists())
            self.assertTrue(sample.exists())
            uploads = list(directory.glob("autorca-upload-*.log"))
            self.assertEqual([path.name for path in uploads], [result["filename"]])


if __name__ == "__main__":
    unittest.main()
