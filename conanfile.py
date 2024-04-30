from conan import ConanFile

class CryptographyPy(ConanFile):

    generators = ["CMakeDeps", "CMakeToolchain"]
    settings = "os", "compiler", "build_type", "arch"
    # Dynamically define requirements
    def requirements(self):
        # List of dependencies without overrides
        self.requires("openssl/3.3.0")

    def build_requirements(self):
        self.tool_requires("cmake/3.28.1")