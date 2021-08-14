from setuptools import setup, find_packages

requirements = [
    'git+https://github.com/eliben/pyelftools',
    'git+https://github.com/williballenthin/python-idb'
]

setup(
    name="unstrip",
    author="David Bouman",
    author_email="dbouman03@gmail.com",
    install_requires=requirements)

