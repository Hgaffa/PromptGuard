from setuptools import setup, find_packages

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="promptguard",
    version="0.1.0",
    author="Hasanain Ghafoor",
    author_email="hgaffa@gmail.com",
    description="A production-ready library for detecting malicious LLM prompts and prompt injection attacks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Hgaffa/promptguard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.11.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    keywords="prompt-injection, llm-security, ai-safety, prompt-guard, nlp",
    project_urls={
        "Bug Reports": "https://github.com/Hgaffa/promptguard/issues",
        "Source": "https://github.com/Hgaffa/promptguard",
        "Documentation": "https://github.com/Hgaffa/promptguard#readme",
    },
)