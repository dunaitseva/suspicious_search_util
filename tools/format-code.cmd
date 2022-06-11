@echo off

set project_dir=project
set src_dir=%project_dir%/src
set include_dir=%project_dir%/include
set tests_dir=tests

set format_file_path=tools\.clang-format

clang-format -i --style=file:%format_file_path% %project_dir%\*.cpp
echo "Formatted %project_dir%"

clang-format -i --style=file:%format_file_path% %src_dir%\*.cpp
echo "Formatted %project_dir%"

clang-format -i --style=file:%format_file_path% %include_dir%\*.h
echo "Formatted %project_dir%"

clang-format -i --style=file:%format_file_path% %tests_dir%\*.cpp
echo "Formatted %project_dir%"
