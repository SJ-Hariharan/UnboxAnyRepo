import unittest

from greeter import greet


class GreetTests(unittest.TestCase):
    def test_greet(self):
        self.assertEqual(greet(" Ada "), "Hello, Ada!")

    def test_empty(self):
        with self.assertRaises(ValueError):
            greet("   ")


if __name__ == "__main__":
    unittest.main()
