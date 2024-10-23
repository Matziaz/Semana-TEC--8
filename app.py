from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_secreta_cambiar_en_produccion'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tienda.db'
db = SQLAlchemy(app)

# Modelos
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nombre = db.Column(db.String(100))
    es_admin = db.Column(db.Boolean, default=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)
    ventas = db.relationship('Venta', backref='usuario', lazy=True)

class Producto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    precio = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    ventas = db.relationship('Venta', backref='producto', lazy=True)
    
class Venta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    total = db.Column(db.Float, nullable=False)

# Decorador para requerir login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor inicia sesión para acceder')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para requerir rol de administrador
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor inicia sesión para acceder')
            return redirect(url_for('login'))
        
        usuario = Usuario.query.get(session['usuario_id'])
        if not usuario or not usuario.es_admin:
            flash('Acceso no autorizado')
            return redirect(url_for('inicio'))
        return f(*args, **kwargs)
    return decorated_function

# Rutas de autenticación y registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        nombre = request.form['nombre']
        
        # Verificar si el usuario o email ya existe
        if Usuario.query.filter_by(username=username).first():
            flash('El nombre de usuario ya está en uso')
            return redirect(url_for('registro'))
        if Usuario.query.filter_by(email=email).first():
            flash('El email ya está registrado')
            return redirect(url_for('registro'))
        
        nuevo_usuario = Usuario(
            username=username,
            password=generate_password_hash(password),
            email=email,
            nombre=nombre,
            es_admin=False
        )
        
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('Registro exitoso. Por favor inicia sesión')
        return redirect(url_for('login'))
    
    return render_template('registro.html')

@app.route('/admin/usuarios')
@admin_required
def admin_usuarios():
    usuarios = Usuario.query.all()
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/usuario/<int:usuario_id>/toggle_admin', methods=['POST'])
@admin_required
def toggle_admin(usuario_id):
    usuario = Usuario.query.get_or_404(usuario_id)
    if usuario.username != 'admin':  # Proteger al admin principal
        usuario.es_admin = not usuario.es_admin
        db.session.commit()
        flash(f"Permisos de administrador {'otorgados' if usuario.es_admin else 'revocados'} para {usuario.username}")
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuario/<int:usuario_id>/eliminar', methods=['POST'])
@admin_required
def eliminar_usuario(usuario_id):
    usuario = Usuario.query.get_or_404(usuario_id)
    if usuario.username != 'admin':  # Proteger al admin principal
        db.session.delete(usuario)
        db.session.commit()
        flash(f"Usuario {usuario.username} eliminado")
    return redirect(url_for('admin_usuarios'))

# Rutas de autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        usuario = Usuario.query.filter_by(username=username).first()
        if usuario and check_password_hash(usuario.password, password):
            session['usuario_id'] = usuario.id
            session['es_admin'] = usuario.es_admin
            flash('Inicio de sesión exitoso')
            return redirect(url_for('inicio'))
        
        flash('Usuario o contraseña incorrectos')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión')
    return redirect(url_for('inicio'))

# Rutas principales
@app.route('/')
def inicio():
    productos = Producto.query.all()
    return render_template('inicio.html', productos=productos)

@app.route('/producto/nuevo', methods=['GET', 'POST'])
@admin_required
def nuevo_producto():
    if request.method == 'POST':
        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        precio = float(request.form['precio'])
        stock = int(request.form['stock'])
        
        producto = Producto(nombre=nombre, descripcion=descripcion,
                          precio=precio, stock=stock)
        db.session.add(producto)
        db.session.commit()
        flash('Producto agregado exitosamente')
        return redirect(url_for('inicio'))
    
    return render_template('nuevo_producto.html')

@app.route('/vender/<int:producto_id>', methods=['POST'])
@login_required
def vender(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    cantidad = int(request.form['cantidad'])
    
    if cantidad <= producto.stock:
        total = producto.precio * cantidad
        venta = Venta(
            producto_id=producto_id,
            usuario_id=session['usuario_id'],
            cantidad=cantidad,
            total=total
        )
        producto.stock -= cantidad
        
        db.session.add(venta)
        db.session.commit()
        flash('Venta realizada con éxito')
    else:
        flash('No hay suficiente stock')
    
    return redirect(url_for('inicio'))

@app.route('/inventario')
@admin_required
def inventario():
    productos = Producto.query.all()
    return render_template('inventario.html', productos=productos)

@app.route('/ventas')
@admin_required
def ventas():
    ventas = Venta.query.join(Producto).order_by(Venta.fecha.desc()).all()
    return render_template('ventas.html', ventas=ventas)

# Función para crear un usuario administrador inicial
def crear_admin():
    admin = Usuario.query.filter_by(username='admin').first()
    if not admin:
        admin = Usuario(
            username='admin',
            password=generate_password_hash('admin123'),
            email='admin@tienda.com',
            nombre='Administrador',
            es_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        
# Función para crear usuarios iniciales
def crear_usuarios_iniciales():
    # Crear admin si no existe
    admin = Usuario.query.filter_by(username='admin').first()
    if not admin:
        admin = Usuario(
            username='admin',
            password=generate_password_hash('admin123'),
            email='admin@tienda.com',
            nombre='Administrador',
            es_admin=True
        )
        db.session.add(admin)
    
    # Crear usuario de prueba si no existe
    usuario = Usuario.query.filter_by(username='usuario').first()
    if not usuario:
        usuario = Usuario(
            username='usuario',
            password=generate_password_hash('usuario123'),
            email='usuario@ejemplo.com',
            nombre='Usuario Prueba',
            es_admin=False
        )
        db.session.add(usuario)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
        crear_admin()
    app.run(debug=True)
