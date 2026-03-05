export function schemaErrorFormatter(errors: Array<{
  instancePath: string;
  keyword: string;
  params: Record<string, unknown>;
  message?: string;
}>): Error {
  const error = errors[0];
  if (!error) return new Error('Validation failed');

  let field = error.instancePath.replace(/^\//, '').replace(/\//g, '.');
  if (!field && error.keyword === 'required') {
    const missingProperty = error.params['missingProperty'];
    field = typeof missingProperty === 'string' ? missingProperty : 'field';
  }

  let message = '';

  if (error.keyword === 'minLength') {
    message = field
      ? `${field.charAt(0).toUpperCase() + field.slice(1)} must be at least ${Number(error.params['limit'])} characters`
      : `Must be at least ${Number(error.params['limit'])} characters`;
  } else if (error.keyword === 'maxLength') {
    message = field
      ? `${field.charAt(0).toUpperCase() + field.slice(1)} must be at most ${Number(error.params['limit'])} characters`
      : `Must be at most ${Number(error.params['limit'])} characters`;
  } else if (error.keyword === 'format' && error.params['format'] === 'email') {
    message = 'Please enter a valid email address';
  } else if (error.keyword === 'format' && error.params['format'] === 'url') {
    message = 'Please enter a valid URL';
  } else if (error.keyword === 'pattern') {
    if (field === 'username') {
      message = 'Username can only contain letters, numbers and underscores';
    } else if (field === 'password') {
      message = 'Password must contain uppercase, lowercase and number';
    } else {
      message = `${field || 'Field'} format is invalid`;
    }
  } else if (error.keyword === 'required') {
    message = `${field.charAt(0).toUpperCase() + field.slice(1)} is required`;
  } else if (error.keyword === 'minimum') {
    message = `${field || 'Field'} must be at least ${Number(error.params['limit'])}`;
  } else if (error.keyword === 'maximum') {
    message = `${field || 'Field'} must be at most ${Number(error.params['limit'])}`;
  } else if (error.keyword === 'enum') {
    const allowedValues = error.params['allowedValues'] as string[] | undefined;
    message = `${field || 'Field'} must be one of: ${allowedValues?.join(', ') || 'allowed values'}`;
  } else if (error.keyword === 'type') {
    message = `${field || 'Field'} must be a ${String(error.params['type'])}`;
  } else {
    message = error.message || 'Validation error';
  }

  return new Error(message);
}
