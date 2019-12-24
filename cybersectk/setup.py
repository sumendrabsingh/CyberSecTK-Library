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
	      ],
      include_package_data=True,
      zip_safe=False)