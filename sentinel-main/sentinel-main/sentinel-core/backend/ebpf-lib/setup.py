from setuptools import setup, find_packages

setup(
    name="sentinel-ebpf-lib",
    version="0.1.0",
    description="SENTINEL eBPF foundation library",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[],
    extras_require={
        "bcc": ["bcc"],
    },
    package_data={
        "": ["compiled/**/*.o"],
    },
)
