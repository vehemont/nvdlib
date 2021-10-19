import pathlib
from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name='nvdlib',
    packages=find_packages(include=['nvdlib']),
    version='0.5.0',
    install_requires = ['requests'],
    description='National Vulnerability Database CPE/CVE API Library',
    author='Vehemont',
    author_email="brad@nvdlib.com",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Vehemont/nvdlib/",
    license='MIT',
)