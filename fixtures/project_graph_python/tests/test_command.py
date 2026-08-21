import os


def test_dangerous_pattern_only_in_test():
    os.system("printf fixture")
