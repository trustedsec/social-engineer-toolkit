from distutils.command.install import install
from setuptools import setup
from shutil import copytree
from os import chmod, mkdir
class Install(install):
    def run(self):
        install.run(self)
        try: mkdir("/etc/setoolkit/")
        except OSError: pass # already exists
        copytree(".", "/usr/share/setoolkit/", dirs_exist_ok=True)
        open("/etc/setoolkit/set.config", "w").write(open("src/core/config.baseline").read())
        open("/usr/local/bin/setoolkit", "w").write("#!/bin/sh\ncd /usr/share/setoolkit\n./setoolkit")
        chmod("/usr/local/bin/setoolkit", 0o755)
setup(
    name="setoolkit",
    version="8.0.3",
    description="Setoolkit is a collection of tools for penetration testers and security researchers. It is particularly useful for Web Penetration Testing and Security Research.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/donno2048/social-engineer-toolkit",
    install_requires=map(lambda line: line.strip(), filter(lambda line: not line.startswith(("#", "\n")), open('requirements.txt').readlines())), # pip3 install -r requirements.txt
    cmdclass={'install': Install},
    include_package_data=True, # not actually needed, but for future packaging
)