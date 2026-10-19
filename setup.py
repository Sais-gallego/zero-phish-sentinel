from setuptools import setup, find_packages

setup(
    name="zero-phish-sentinel",
    version="1.0.0",
    author="Sais-gallego",
    description="Advanced Anti-Phishing & Malicious URL Lexical/Heuristic Analysis Engine",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Sais-gallego/zero-phish-sentinel",
    packages=find_packages(),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "zerophish=zerophish.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Operating System :: OS Independent",
    ],
)
