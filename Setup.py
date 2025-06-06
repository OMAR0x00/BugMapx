from setuptools import setup, find_packages

setup(
    name='bugmapx',
    version='0.1',
    packages=find_packages(),
    install_requires=open('requirements.txt').read().splitlines(),
    entry_points={
        'console_scripts': [
            'bugmapx=bugmapx.engine:main',  # Make sure `main()` exists in engine.py
        ],
    },
)
