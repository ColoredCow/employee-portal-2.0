### Prerequisites
1. Python 3.9
2. Docker

### Installation Guideline
1. Install pre-commit and commit-linter
   ```sh
   pip install pre-commit
   pip install commit-linter
   ```
2. Install necessary packages for development purposes locally using pipenv
   ```sh
   pipenv shell
   pipenv install --dev
   ```
3. Create a `.env` file by duplicating `.env.example`. Put the values according to your system setup.
4. Create a file to capture logs while development. The file path should be `logs/app.log` inside the project root directory.
5. Run Docker environment
   ```sh
   docker compose up --build
   ```
   Note: The `--build` is only need when you make any dependencies changes in the project.


### Testing
After creating virtual environment using pipenv. Execute the following command to run test cases
1. Run all the test cases
   ```sh
   pytest .
   ```
2. Run test cases of specific module
   ```sh
   pytest tests/<module_name>
   ```
3. 2. Run a specific test cases of
   ```sh
   pytest tests/<module_name>::<function_name>
   ```
