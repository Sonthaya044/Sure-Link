from flask import Blueprint, render_template

core_bp = Blueprint('core', __name__)

@core_bp.route('/')
def index():
    return render_template('home.html')

@core_bp.route('/history')
def history():
    return render_template('history.html')
