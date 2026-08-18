from setuptools import setup, find_packages

setup(
    name="kernel-agent-ebpf",
    version="1.0.0",
    description="The Linux Kernel eBPF Telemetry Probe & Ring-0 Sandbox Guard for Autonomous AI Agents",
    author="Ahmed Hassan",
    author_email="ahmed.alaa.hassan25@gmail.com",
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: C",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
    ],
)
