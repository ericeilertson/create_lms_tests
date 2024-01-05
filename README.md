This application creates LMS test vectors suitable for use in Caliptra.

sample run command: create_lms_tests --n 32 --w 8 --tree-height 5 --tests 1 --filename lms_tests_n32_w8.rs

Currently the application will not create more than 16 tests in a single test file.  Since these tests are run as ROM files in Caliptra they need to fit in the 48 KB rom limit.
