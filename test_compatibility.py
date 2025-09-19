#!/usr/bin/env python3
"""
Simple compatibility test for Flask dependency updates
"""
import sys

def test_imports():
    """Test that all required modules can be imported"""
    try:
        import flask
        print(f"✓ Flask {flask.__version__} imported successfully")
        
        import werkzeug
        print(f"✓ Werkzeug {werkzeug.__version__} imported successfully")
        
        import jinja2
        print(f"✓ Jinja2 {jinja2.__version__} imported successfully")
        
        import sqlalchemy
        print(f"✓ SQLAlchemy {sqlalchemy.__version__} imported successfully")
        
        import requests
        print(f"✓ Requests {requests.__version__} imported successfully")
        
        import yaml
        print(f"✓ PyYAML imported successfully")
        
        import PIL
        print(f"✓ Pillow {PIL.__version__} imported successfully")
        
        import cryptography
        print(f"✓ Cryptography {cryptography.__version__} imported successfully")
        
        import urllib3
        print(f"✓ urllib3 {urllib3.__version__} imported successfully")
        
        import lxml
        print(f"✓ lxml {lxml.__version__} imported successfully")
        
        import click
        print(f"✓ Click {click.__version__} imported successfully")
        
        import itsdangerous
        print(f"✓ itsdangerous {itsdangerous.__version__} imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_flask_app():
    """Test basic Flask app functionality"""
    try:
        from app import app
        with app.test_client() as client:
            response = client.get('/')
            if response.status_code == 200:
                print("✓ Flask app basic functionality works")
                return True
            else:
                print(f"✗ Flask app returned status code: {response.status_code}")
                return False
    except Exception as e:
        print(f"✗ Flask app test failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing Flask dependency compatibility...")
    print("=" * 50)
    
    imports_ok = test_imports()
    print()
    
    if imports_ok:
        app_ok = test_flask_app()
        if imports_ok and app_ok:
            print("✓ All compatibility tests passed!")
            sys.exit(0)
    
    print("✗ Some tests failed. Please check compatibility.")
    sys.exit(1)