@echo off
set build_dir=build
set cmake_source_dir=.
set generator=Ninja

rmdir /s /q build

set testing=ON
cmake -S %cmake_source_dir% -B %build_dir% -G %generator% -DTEST=%testing%
cd build
ninja
cd ..
