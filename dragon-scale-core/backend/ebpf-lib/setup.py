from setuptools import setup, find_packages

setup(
    name="dragon-scale-ebpf-lib",
    version="0.1.0",
    description="DRAGON_SCALE eBPF foundation library",
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
