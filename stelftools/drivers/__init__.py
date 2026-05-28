"""Console-script entry points for stelftools.

Each module here ties one user-facing CLI to the library packages:
``bruteforce`` drives the matcher against many candidate signatures
per target, ``symbolize`` writes the elected matches back into the
ELF, and ``sigfetch`` populates the on-disk signature tree from a
published Release attachment set.
"""
