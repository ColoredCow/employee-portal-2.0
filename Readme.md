### Prerequisites
1. Python 3.9
2. Docker

### Installation Guideline
1. Create a `.env` file by duplicating `.env.example`. Put the values according to your system setup.
2. Create a file to capture logs while development. The file path should be `logs/app.log` inside the project root directory.
3. You can run you application using a single command:
   ```sh
   docker compose up --build
   ```
   Note: The `--build` is only need when you make any dependencies changes in the project.

### Pre-commit Hooks Installation
While doing development its good to follow best practices used in the industry. We have taken care of it by adding some tools for checking the sanity of your code when you make any commit to GitHub. To install these development tools, follow the steps mentioned below:
1. Install pre-commit and commit-linter to ensure that every time you make a commit the checks should be triggered.
   ```sh
   pip install pre-commit
   pip install commit-linter
   ```
2. Start a virtual environment
   ```sh
   pipenv shell
   ```
   Note: if you dont have pipenv then install it using `pip install pipenv`

3. Install necessary packages for development purposes locally using pipenv
   ```sh
   pipenv install --dev
   ```
   Note: Whenever the checks are running, make sure the you have started the virtual environment


### Testing
To test the functionality of your code and test cases. Run the test cases using the below mentioned commands after creating virtual environment using pipenv.
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
