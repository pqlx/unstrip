from setuptools import setup, find_packages

requirements = [
    'pyelftools',
    'python-idb',
    'python-slugify',
    'pytest'
]

setup(
    name="unstrip",
    author="David Bouman",
    author_email="dbouman03@gmail.com",
    install_requires=requirements,
    entry_points={'console_scripts': ['unstrip = unstrip.__main__:main']}
    )

