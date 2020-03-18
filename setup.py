import os
from setuptools import setup


NAME = 'mlibinjector'

# Load the package's __version__.py module as a dictionary.
# keep the line below as-is, use the __version__.py file instead
here = os.path.abspath(os.path.dirname(__file__))
about = {}
with open(os.path.join(here, NAME, '__info__.py')) as f:
	exec(f.read(), about)

setup(
	name=NAME,
	description=about['__description__'],
	version=about['__version__'],
	author=about['__authors__'][0],
	install_requires=[
		"lief >= 0.9.0",
		"termcolor"
	],
	packages=[NAME],
	entry_points={
		'console_scripts': [
			"mlibinjector = mlibinjector.__main__:main"
		]

	},
	include_package_data=True,
	zip_safe=False,
	license='LGPLv3',
)
