from setuptools import setup

long_description = """
    A prototype Python router daemon

    More information at https://github.com/samrussell/trasa
"""

setup(
    name='trasa',
    description='A prototype Python router daemon',
    long_description=long_description,
    version='0.0.1',
    url='https://github.com/samrussell/trasa',
    author='Sam Russell',
    author_email='sam.h.russell@gmail.com',
    license='Affero GPL v3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3'
    ],
    keywords='ldp trasa mpls routing sdn networking',
    packages=['trasa'],
    python_requires='>=3',
    install_requires=[
        'eventlet',
        'pyyaml'
    ]
)
