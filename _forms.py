from wtforms import Form, \
                    BooleanField, \
                    TextField, \
                    PasswordField, \
                    validators


class UserRegistrationForm(Form):
    username = TextField(
        'Username',

        [
         validators.Required(), 
		 validators.Regexp('^\w+$', 
                           message="Username must contain only letters numbers or underscore"),
		 validators.Length(min=5, 
                           max=25, 
                           message="Username must be between 5 & 25 characters")
        ],

        render_kw={
            "placeholder": "Enter a Username", 
            "class": "form-control"
        },
    )

    firstname = TextField('First Name', 
                          [validators.Required()], 
                          render_kw={"placeholder": "Enter First Name", "class": "form-control"})

    lastname = TextField('Last Name', 
                         [validators.Required()], 
                         render_kw={"placeholder": "Enter Last Name", "class": "form-control"})

    email = TextField('Email', 
                      [validators.Email(message=u'Valid email is required')], 
                      render_kw={"placeholder": "Enter a Email Address", "class": "form-control"})

    password = PasswordField('New Password', 
                             [validators.Required(),validators.EqualTo('confirm', message='Passwords must match')], 
                             render_kw={"placeholder": "Enter a Password", "class": "form-control"})

    confirm = PasswordField('Repeat Password',render_kw={"placeholder": "Re-type Password", "class": "form-control"})

    accept_tos = BooleanField('By registering, I agree to the terms and conditions.', 
                              [validators.Required()], 
                              render_kw={"type": "checkbox"})

