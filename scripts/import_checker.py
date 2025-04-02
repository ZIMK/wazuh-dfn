#!/usr/bin/env python
"""Check for imports that reference classes not defined in the imported module or its __init__.py.

This script analyzes Python imports throughout the codebase and detects when imported
classes, functions, or constants don't exist in the module they're imported from.

Features:
- Detects improper imports in any context (including inside functions, methods,
  conditional blocks, and try/except blocks)
- Handles __init__.py re-exports properly
- Supports checking classes, functions, and constants
- Automatically detects package structure
"""
import ast
import os
import sys
from pathlib import Path

PYPROJECT_FILE = "pyproject.toml"


class ClassDefinitionCollector(ast.NodeVisitor):
    """Collect all class definitions in a module."""

    def __init__(self):
        self.defined_classes: set[str] = set()

    def visit_ClassDef(self, node):  # noqa: N802
        self.defined_classes.add(node.name)
        self.generic_visit(node)


class FunctionDefinitionCollector(ast.NodeVisitor):
    """Collect all function definitions in a module."""

    def __init__(self):
        self.defined_functions: set[str] = set()

    def visit_FunctionDef(self, node):  # noqa: N802
        self.defined_functions.add(node.name)
        self.generic_visit(node)


class ConstantDefinitionCollector(ast.NodeVisitor):
    """Collect all constant definitions (uppercase variables) in a module."""

    def __init__(self):
        self.defined_constants: set[str] = set()

    def visit_Assign(self, node):  # noqa: N802
        # Look for assignments to uppercase variables (constants)
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.isupper():
                self.defined_constants.add(target.id)
        self.generic_visit(node)


class ImportCollector(ast.NodeVisitor):
    """Collect all imported classes, functions, and constants in a module."""

    def __init__(self):
        self.imported_classes: dict[str, str] = {}  # class_name -> module_path
        self.imported_functions: dict[str, str] = {}  # function_name -> module_path
        self.imported_constants: dict[str, str] = {}  # constant_name -> module_path

    def visit_ImportFrom(self, node):  # noqa: N802
        module_path = node.module
        if module_path is None:  # relative import with no module
            return

        for name in node.names:
            if name.name == "*":
                continue  # Skip wildcard imports

            if name.name[0].isupper():
                if name.name.isupper():  # All uppercase = constant
                    self.imported_constants[name.name] = module_path
                else:  # First letter uppercase = class
                    self.imported_classes[name.name] = module_path
            else:  # lowercase function
                self.imported_functions[name.name] = module_path

        self.generic_visit(node)


def determine_package_name(package_root):  # NOSONAR
    """Extract the package name from pyproject.toml."""
    package_root = Path(package_root)
    # Try to get package name from pyproject.toml
    pyproject_path = package_root / PYPROJECT_FILE
    if pyproject_path.exists():
        try:
            with Path(pyproject_path).open() as f:
                content = f.read()
                # Look for name in [project] section or in tool.poetry section
                for line in content.split("\n"):
                    if "name" in line and "=" in line:
                        # Simple parsing for name = "package"
                        parts = line.split("=")
                        if len(parts) >= 2:
                            name = parts[1].strip().strip("\"'").split()[0]
                            if name:
                                return name
        except Exception as e:
            print(f"Error reading pyproject.toml: {e}", file=sys.stderr)

    # Fallback: use the directory name of the package root
    return package_root.name


class AllDefinitionCollector(ast.NodeVisitor):
    """Collect all names defined in __all__ in a module."""

    def __init__(self):
        self.defined_in_all: set[str] = set()
        self.has_all = False

    def visit_Assign(self, node):  # noqa: N802 NOSONAR
        # Check for __all__ = [...] syntax
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                self.has_all = True
                if isinstance(node.value, ast.List):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Str):
                            self.defined_in_all.add(elt.s)
        self.generic_visit(node)


class ImportUsageChecker(ast.NodeVisitor):
    """Check if imported classes, functions and constants exist in their source modules."""

    def __init__(self, file_path, package_root, check_functions=False, check_constants=False):
        self.file_path = Path(file_path)
        self.package_root = Path(package_root)
        # (name, module_path, line_number, type: 0=class, 1=function, 2=constant)
        self.issues: list[tuple[str, str, int, int]] = []
        self.module_classes_cache: dict[str, set[str]] = {}  # module_path -> set of classes
        self.module_functions_cache: dict[str, set[str]] = {}  # module_path -> set of functions
        self.module_constants_cache: dict[str, set[str]] = {}  # module_path -> set of constants
        self.module_imports_cache: dict[str, dict[str, str]] = {}  # module_path -> {class_name -> source_module}
        self.package_name = determine_package_name(package_root)
        self.check_functions = check_functions
        self.check_constants = check_constants

    def _determine_package_name(self):
        """Extract the package name from pyproject.toml."""
        return determine_package_name(self.package_root)

    def _get_module_file_path(self, module_path):
        """Convert a module path to a file path."""
        rel_path = Path(*module_path.split("."))
        py_file = self.package_root / f"{rel_path}.py"

        if py_file.exists():
            return py_file

        # Check if it's a package with __init__.py
        init_file = self.package_root / rel_path / "__init__.py"
        if init_file.exists():
            return init_file

        return None

    def _get_module_classes(self, module_path):
        """Get all classes defined in the specified module."""
        if module_path in self.module_classes_cache:
            return self.module_classes_cache[module_path]

        defined_classes = set()
        file_path = self._get_module_file_path(module_path)

        if file_path:
            try:
                with Path(file_path).open() as f:
                    tree = ast.parse(f.read())
                    collector = ClassDefinitionCollector()
                    collector.visit(tree)
                    defined_classes = collector.defined_classes
            except Exception as e:
                print(f"Error analyzing module {module_path}: {e}", file=sys.stderr)

        self.module_classes_cache[module_path] = defined_classes
        return defined_classes

    def _get_module_functions(self, module_path):
        """Get all functions defined in the specified module."""
        if not self.check_functions:
            return set()

        if module_path in self.module_functions_cache:
            return self.module_functions_cache[module_path]

        defined_functions = set()
        file_path = self._get_module_file_path(module_path)

        if file_path:
            try:
                with Path(file_path).open() as f:
                    tree = ast.parse(f.read())
                    collector = FunctionDefinitionCollector()
                    collector.visit(tree)
                    defined_functions = collector.defined_functions
            except Exception as e:
                print(f"Error analyzing module {module_path}: {e}", file=sys.stderr)

        self.module_functions_cache[module_path] = defined_functions
        return defined_functions

    def _get_module_constants(self, module_path):
        """Get all constants defined in the specified module."""
        if not self.check_constants:
            return set()

        if module_path in self.module_constants_cache:
            return self.module_constants_cache[module_path]

        defined_constants = set()
        file_path = self._get_module_file_path(module_path)

        if file_path:
            try:
                with Path(file_path).open() as f:
                    tree = ast.parse(f.read())
                    collector = ConstantDefinitionCollector()
                    collector.visit(tree)
                    defined_constants = collector.defined_constants
            except Exception as e:
                print(f"Error analyzing module {module_path}: {e}", file=sys.stderr)

        self.module_constants_cache[module_path] = defined_constants
        return defined_constants

    def _get_module_imports(self, module_path):
        """Get all classes imported in the specified module."""
        if module_path in self.module_imports_cache:
            return self.module_imports_cache[module_path]

        imported_classes = {}
        file_path = self._get_module_file_path(module_path)

        if file_path:
            try:
                with Path(file_path).open() as f:
                    tree = ast.parse(f.read())
                    collector = ImportCollector()
                    collector.visit(tree)
                    imported_classes = collector.imported_classes
            except Exception as e:
                print(f"Error analyzing imports in module {module_path}: {e}", file=sys.stderr)

        self.module_imports_cache[module_path] = imported_classes
        return imported_classes

    def _get_module_all(self, module_path):
        """Get all names defined in __all__ in the specified module."""
        file_path = self._get_module_file_path(module_path)

        if not file_path:
            return set(), False

        try:
            with Path(file_path).open() as f:
                tree = ast.parse(f.read())
                collector = AllDefinitionCollector()
                collector.visit(tree)
                return collector.defined_in_all, collector.has_all
        except Exception as e:
            print(f"Error analyzing __all__ in module {module_path}: {e}", file=sys.stderr)
            return set(), False

    def _is_valid_init_reexport(self, module_path, class_name):
        """Check if this is a valid re-export in an __init__.py file."""
        # If not an __init__ module, return False
        if not module_path.endswith("__init__"):
            return False

        # Get the package directory
        package_path = module_path[:-9]  # Remove '.__init__'

        imports = self._get_module_imports(module_path)
        if class_name not in imports:
            return False

        source_module = imports[class_name]

        # Check if the source module is part of the same package
        return bool(source_module.startswith(package_path) or source_module.startswith("."))

    def _class_exists_in_module_or_reexports(self, module_path, class_name):
        """Check if the class exists in the module or is a valid re-export."""
        # Check if the class is defined directly in the module
        if class_name in self._get_module_classes(module_path):
            return True

        # Check if in __all__
        all_names, has_all = self._get_module_all(module_path)
        if has_all and class_name in all_names:
            return True

        # Check if this is an __init__.py file
        if module_path.endswith("__init__"):
            return self._is_valid_init_reexport(module_path, class_name)

        return False

    def visit_ImportFrom(self, node):  # noqa: N802, PLR0912 NOSONAR
        module_path = node.module
        if module_path is None:  # relative import with no module
            return

        # Improved check for external imports
        # If the import doesn't start with a dot (relative import), check if it's from our package
        if not module_path.startswith("."):
            top_module = module_path.split(".")[0]
            if top_module != self.package_name:
                # This is an external package import, skip it
                return
        else:
            # For relative imports, check if the resolved module exists in our package
            file_dir = self.file_path.parent
            rel_to_pkg = file_dir.relative_to(self.package_root) if self.package_root != file_dir else Path()
            if str(rel_to_pkg) == ".":
                current_pkg_path = ""
            else:
                current_pkg_path = str(rel_to_pkg).replace(os.sep, ".")

            # Resolve the module path
            resolved_module_path = module_path.lstrip(".")
            if module_path != ".":
                if module_path.startswith("."):
                    resolved_module_path = f"{current_pkg_path}.{module_path.lstrip('.')}"
                else:
                    resolved_module_path = module_path

            # Skip if we can't resolve the module path
            if not self._get_module_file_path(resolved_module_path):
                return

        for name in node.names:
            if name.name == "*":  # Skip wildcard imports
                continue

            if name.name.isupper() and self.check_constants:
                # Check constant imports (all uppercase)
                constants = self._get_module_constants(module_path)
                if name.name not in constants:
                    self.issues.append((name.name, module_path, node.lineno, 2))  # 2 constant
            elif name.name[0].isupper():
                # Check class imports (uppercase first letter)
                if not self._class_exists_in_module_or_reexports(module_path, name.name):
                    self.issues.append((name.name, module_path, node.lineno, 0))  # 0 class
            elif self.check_functions:
                # Check function imports (lowercase)
                functions = self._get_module_functions(module_path)
                if name.name not in functions:
                    self.issues.append((name.name, module_path, node.lineno, 1))  # 1 function

        self.generic_visit(node)


def find_package_root(path):
    """Find the directory containing pyproject.toml."""
    path = Path(path).resolve()

    # If path is a file, use its parent directory
    if path.is_file():
        path = path.parent

    # Check if pyproject.toml exists in the provided directory
    if (path / PYPROJECT_FILE).exists():
        return path

    # Look up the directory tree
    while path != path.parent:  # Until we reach filesystem root
        if (path / PYPROJECT_FILE).exists():
            return path
        path = path.parent

    # If we can't find pyproject.toml, return the original directory
    return Path(path)


def detect_source_directory(package_root, package_name=None):
    """Attempt to detect the source directory from the package root.

    Strategy:
    1. Check for src/package_name directory (converting dashes to underscores)
    2. Check for src/ directory
    3. Check for a directory matching the package name (with underscores)
    4. Fall back to the package root itself
    """
    # If we have a src directory, that's likely our source code
    src_dir = package_root / "src"
    if src_dir.is_dir():
        # Check for a directory matching the package_name with underscores instead of dashes
        if package_name:
            # Convert dashes to underscores (common Python package convention)
            underscore_name = package_name.replace("-", "_")
            pkg_src_dir = src_dir / underscore_name
            if pkg_src_dir.is_dir():
                return pkg_src_dir

            # Try the original package name
            pkg_src_dir = src_dir / package_name
            if pkg_src_dir.is_dir():
                return pkg_src_dir

        # Otherwise just use src/
        return src_dir

    # Look for a directory matching the package name
    if package_name:
        # Try with underscores
        underscore_name = package_name.replace("-", "_")
        pkg_dir = package_root / underscore_name
        if pkg_dir.is_dir():
            return pkg_dir

        # Try original name
        pkg_dir = package_root / package_name
        if pkg_dir.is_dir():
            return pkg_dir

    # Fall back to package root itself
    return package_root


def check_all_imports(  # noqa: PLR0912 NOSONAR
    source_dir, package_root=None, verbose=False, check_functions=False, check_constants=False, ignore_patterns=None
):
    """Check all Python files in the source directory for incorrect imports.

    Args:
        source_dir: Directory containing Python files to check
        package_root: Directory containing pyproject.toml (package metadata)
        verbose: Whether to print detailed information during checking
        check_functions: Whether to check function/method imports (not just classes)
        check_constants: Whether to check constant imports (all uppercase variables)
        ignore_patterns: List of patterns to ignore (glob patterns)

    Returns:
        tuple: (list of issue tuples, number of files checked)
    """
    results = []
    source_path = Path(source_dir)
    ignore_patterns = ignore_patterns or []

    # If package_root is not provided, try to find it
    if package_root is None:
        package_root = find_package_root(source_path)
    else:
        package_root = Path(package_root)

    file_count = 0
    if verbose:
        print(f"\nScanning Python files in {source_path}...")

    import fnmatch

    def should_ignore(file_path):
        """Check if a file should be ignored based on patterns."""
        rel_path = file_path.relative_to(source_path)
        return any(fnmatch.fnmatch(str(rel_path), pattern) for pattern in ignore_patterns)

    for root, _, files in os.walk(source_path):
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file

                # Skip ignored files
                if should_ignore(file_path):
                    if verbose:
                        print(f"Skipping ignored file: {file_path}")
                    continue

                file_count += 1

                if verbose:
                    print(f"Checking file: {file_path}")

                try:
                    with Path(file_path).open() as f:
                        tree = ast.parse(f.read())
                        checker = ImportUsageChecker(file_path, package_root, check_functions, check_constants)
                        checker.visit(tree)

                        for name, module_path, line_number, item_type in checker.issues:
                            item_type_str = ["Class", "Function", "Constant"][item_type]
                            results.append((str(file_path), name, module_path, line_number, item_type))
                            if verbose:
                                print(
                                    f"  ISSUE: {item_type_str} '{name}' imported from '{module_path}' "
                                    "but not defined there"
                                )
                except SyntaxError as e:
                    print(f"Syntax error in {file_path}: {e}", file=sys.stderr)

    if verbose:
        print(f"\nFinished checking {file_count} Python files")
        print(f"Found {len(results)} issues")

    # Return both the issues and the file count
    return results, file_count


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Check for imports that reference classes not defined in the imported module."
    )
    parser.add_argument("source_dir", nargs="?", default=None, help="Directory containing Python files to check")
    parser.add_argument(
        "--package-root", "-p", dest="package_root", help="Directory containing pyproject.toml (project root)"
    )
    parser.add_argument("--dry-run", "-d", action="store_true", help="Only detect paths without checking imports")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed progress information")
    parser.add_argument(
        "--check-functions", "-f", action="store_true", help="Also check function/method imports (not just classes)"
    )
    parser.add_argument(
        "--check-constants", "-c", action="store_true", help="Also check constant imports (all uppercase variables)"
    )
    parser.add_argument(
        "--check-all", "-a", action="store_true", help="Check all imports (classes, functions, and constants)"
    )
    parser.add_argument(
        "--ignore", "-i", action="append", help="Glob pattern of files to ignore (can be used multiple times)"
    )

    args = parser.parse_args()

    # If --check-all is used, enable all checks
    if args.check_all:
        args.check_functions = True
        args.check_constants = True

    # Find the package root first
    if args.package_root:
        package_root = Path(args.package_root)
    else:
        # Use current directory or provided source directory to find package root
        start_path = args.source_dir or Path.cwd()
        package_root = find_package_root(start_path)

    print(f"Using package root: {package_root}")
    print(f"pyproject.toml path: {package_root / 'pyproject.toml'}")

    # Get package name from pyproject.toml
    package_name = determine_package_name(package_root)
    print(f"Detected package name: {package_name}")

    # Now determine the source directory
    if args.source_dir:
        source_dir = Path(args.source_dir)
        print(f"Using specified source directory: {source_dir}")
    else:
        # Auto-detect source directory
        source_dir = detect_source_directory(package_root, package_name)
        print(f"Auto-detected source directory: {source_dir}")

    # Exit early if this is a dry run
    if args.dry_run:
        print("\nDRY RUN - Paths detected:")
        print(f"  Package root:        {package_root}")
        print(f"  pyproject.toml:      {package_root / 'pyproject.toml'}")
        print(f"  Source directory:    {source_dir}")
        print(f"  Package name:        {package_name}")

        if args.verbose:
            # Additional information about package structure
            print("\nPackage structure understanding:")
            print(f"  Import statements using '{package_name}' will be checked")
            if package_name != package_name.replace("-", "_"):
                print("  Note: Package name contains dashes, but Python module would use underscores")
                print(
                    f"        ('{package_name}' in imports would be '{package_name.replace('-', '_')}' in filesystem)"
                )

        sys.exit(0)

    issues, file_count = check_all_imports(
        source_dir, package_root, args.verbose, args.check_functions, args.check_constants, args.ignore
    )

    if issues:
        for file_path, name, module_path, line_number, item_type in issues:
            item_type_str = ["Class", "Function", "Constant"][item_type]
            print(
                f"{file_path}:{line_number}: {item_type_str} '{name}' "
                f"imported from '{module_path}' but not defined there"
            )
        sys.exit(1)
    else:
        print(f"All checks passed! Scanned {file_count} Python files.")
        sys.exit(0)
