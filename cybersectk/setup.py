from setuptools import setup, find_packages
 
setup(name='cybersectk',
      version='1.0',
      url='https://github.com/sumendrabsingh/cybersectk',
      license='MIT',
      author='SumendraBSingh',
      author_email='sumendrasingh@gmail.com',
      description='Library for Machine Learning CyberSec feature extraction',
      packages=['cybersectk'],
      install_requires=[
            'scapy',
            'pandas',
            'scikit-learn',
            ],
        classifiers=[
            'Development Status :: 4 - Beta',
            'Programming Language :: Python :: 3.7',
            'Topic :: Software Development :: Libraries :: Python Modules',
        ],
      include_package_data=True,
      zip_safe=False)