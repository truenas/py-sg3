from setuptools import setup, Extension
from Cython.Build import cythonize

Exts = [
    Extension("libsg3.ses", ["libsg3/ses/ses.pyx"],
              libraries=["sgutils2"],
              library_dirs=["/usr/lib"],
              include_dirs=["/usr/include"],
              define_macros=[("HAVE_LINUX_TYPES_H", None)])
]

setup(
    name="python3-sg3",
    version="0.1.0",
    license="BSD-3-Clause",
    setup_requires=[
        "setuptools>=45.0",
        "Cython",
    ],
    ext_modules = cythonize(Exts)
)
