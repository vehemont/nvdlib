import pathlib
from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name='nvdlib',
    packages=find_packages(include=['nvdlib']),
    version='0.7.4',
    install_requires=['requests==2.28.2', 'aiohttp==3.8.4'],
    extras_require={
        "dev": [
            "responses==0.18.0",
            "pytest==7.0.1",
        ]
    },
    python_requires='>3.7.9',
    description='National Vulnerability Database CPE/CVE API Library for Python',
    author='Vehemont',
    author_email="brad@nvdlib.com",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Vehemont/nvdlib/",
    license='MIT',
)
