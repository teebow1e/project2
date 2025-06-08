# prj2

## deployment
```
# Create a new project directory
mkdir jupyter-project
cd jupyter-project

# Initialize a project
uv init --bare

# Add Jupyter and other dependencies
uv add --dev jupyter matplotlib pandas numpy
uv run jupyter lab
```
