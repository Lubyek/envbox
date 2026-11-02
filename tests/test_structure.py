"""Проверки структуры проекта и сборки: python3 -m unittest discover -s tests"""
import ast
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))

import build  # noqa: E402


def run(*args, **kw):
    env = dict(os.environ, HOME=tempfile.mkdtemp(), XDG_DATA_HOME="")
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, env=env, timeout=120, **kw)


class BuildTests(unittest.TestCase):
    def test_build_passes(self):
        build.build(write=False)

    def test_dist_is_up_to_date(self):
        with open(build.DIST, encoding="utf-8") as f:
            self.assertEqual(f.read(), build.build_text(), "dist/envbox.py устарел: python3 build.py")

    def test_bundle_has_no_relative_imports(self):
        tree = ast.parse(build.build_text())
        self.assertFalse([n.lineno for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level])

    def test_version_same_in_dev_and_bundle(self):
        from envbox.version import ENVBOX_VERSION
        for entry in ("dev.py", "dist/envbox.py"):
            r = run(os.path.join(ROOT, entry), "version")
            self.assertEqual(r.stdout.strip(), ENVBOX_VERSION, r.stderr)

    def test_non_gui_modules_import_without_gtk(self):
        mods = [m for m in build.module_files() if not m.startswith("gui")]
        code = "import sys; sys.path.insert(0, %r)\n" % os.path.join(ROOT, "src") + \
            "".join(f"import envbox.{m}\n" for m in mods) + "assert not any(k.startswith('gi') for k in sys.modules)\n"
        r = run("-c", code)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_envbox_sh_syntax(self):
        path = os.path.join(ROOT, "src", "envbox", "resources", "envbox.sh")
        r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class AiGuideTests(unittest.TestCase):
    """AI_GUIDE.md — путеводитель для ИИ: он не должен расходиться с кодом."""

    @staticmethod
    def guide():
        with open(os.path.join(ROOT, "AI_GUIDE.md"), encoding="utf-8") as f:
            return f.read()

    def test_mentioned_paths_exist(self):
        import re
        bases = ("", "src/envbox/", "src/envbox/resources/")
        paths = re.findall(r"`((?:src/envbox/|tests/|dist/|legacy/|net/|core/|cdp/|gui/|resources/)[A-Za-z0-9_./-]+)`", self.guide())
        missing = [p for p in sorted(set(paths))
                   if not any(os.path.exists(os.path.join(ROOT, b, p)) for b in bases)]
        self.assertEqual(missing, [], "AI_GUIDE.md ссылается на несуществующие пути")

    def test_mentioned_functions_exist(self):
        import re
        defined = set()
        for path in build.module_files().values():
            with open(path, encoding="utf-8") as f:
                for n in ast.walk(ast.parse(f.read())):
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        defined.add(n.name)
        with open(os.path.join(ROOT, "src", "envbox", "resources", "envbox.sh"), encoding="utf-8") as f:
            sh = f.read()
        names = set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)\(\)`", self.guide()))
        names -= {"_build_gui"}      # создаётся сборщиком, в исходниках её нет
        missing = sorted(n for n in names if n not in defined and not re.search(rf"^{n}\(\)", sh, re.M))
        self.assertEqual(missing, [], "AI_GUIDE.md упоминает функции, которых нет в коде")


class PureFunctionTests(unittest.TestCase):
    def test_split_hostport(self):
        from envbox.net.common import split_hostport
        self.assertEqual(split_hostport("example.com:8080", 80), ("example.com", 8080))
        self.assertEqual(split_hostport("[::1]:9", 80), ("::1", 9))
        self.assertEqual(split_hostport("a.b", 443), ("a.b", 443))

    def test_is_public(self):
        from envbox.net.common import is_public
        self.assertTrue(is_public("8.8.8.8"))
        self.assertFalse(is_public("10.0.0.1"))

    def test_split_proxy_url(self):
        from envbox.core.upstream import split_proxy_url
        self.assertEqual(split_proxy_url("socks5h://u:p@h:1080"), ("socks5h://h:1080", "u:p"))

    def test_seccomp_program_is_whole_instructions(self):
        from envbox.net.seccomp import seccomp_program_x86_64
        self.assertEqual(len(seccomp_program_x86_64()) % 8, 0)


if __name__ == "__main__":
    unittest.main()
