import quickscope
import unittest
import os

basedir = os.path.dirname(os.path.abspath(__file__))

class TestIgnores(unittest.TestCase):
    def test_ignores(self):
        manager = quickscope.shooter.CorpusManager(os.path.join(basedir, 'corpora', 'ignores'), '', 1, quickscope.shooter.Everyone())
        scripts = set(child.script_name for child in manager.children)
        assert scripts == {os.path.join(basedir, 'corpora', 'ignores', stem) for stem in ('a.py', 'c.b', 'subdir1/a.py')}
