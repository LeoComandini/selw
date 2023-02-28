from setuptools import setup, find_packages

setup(
    name='selw',
    version='0.1',
    description='Simple Elements Wallet',
    python_requires='>=3.6.0',
    author='Leonardo Comandini',
    license='MIT',
    packages=find_packages(exclude=['tests']),
    install_requires=['wallycore', 'requests'],
    url='https://github.com/LeoComandini/selw',
    classifiers=[
        'Development Status :: 1 - Planning',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
    ],
)
