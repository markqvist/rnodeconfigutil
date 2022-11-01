import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="rnodeconf",
    version="1.3.1",
    author="Mark Qvist",
    author_email="mark@unsigned.io",
    description="Configuration Utility for RNode hardware",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/markqvist/rnodeconfigutil",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points= {
        'console_scripts': ['rnodeconf=rnodeconf:main']
    },
    install_requires=['pyserial>=3.5', 'cryptography', "rns>=0.3.18"],
    python_requires='>=3.6',
)
