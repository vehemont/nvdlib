from setuptools import find_packages, setup
setup(
    name='nvdlib',
    packages=find_packages(include=['nvdlib']),
    version='0.3.0',
    description='National Vulnerability Database CPE/CVE API Library',
    author='Brad Riley',
    license='MIT',
)