require('dotenv/config');
const jwt = require('jsonwebtoken');
const { UserService } = require('../services');

const secret = process.env.JWT_SECRET;

// const isBodyValid = (username, password) => username && password;

const validateBody = (body, res) => {
  const { username, password } = body;

  if (!username || !password) {
    res
      .status(401)
      .json({ message: 'É necessário usuário e senha para fazer login' });
    return false;
  }

  return true;
};

const validateUserOrPassword = (user, password, res) => {
  if (!user || user.password !== password) {
    res
      .status(401)
      .json({ message: 'Usuário não existe ou senha inválida' });
    return false;
  }

  return true;
};

module.exports = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!validateBody(req.body, res)) return;

    const user = await UserService.getByUsername(username);

    if (!validateUserOrPassword(user, password, res)) return;

    /* Criamos uma config básica para o nosso JWT, onde:
    expiresIn -> significa o tempo pelo qual esse token será válido;
    algorithm -> algoritmo que você usará para assinar sua mensagem */

    // A propriedade expiresIn aceita o tempo de forma bem descritiva.
    // Por exemplo: '7d' = 7 dias; '8h' = 8 horas.
    const jwtConfig = {
      expiresIn: '7d',
      algorithm: 'HS256',
    };

    /* Aqui é quando assinamos de fato nossa mensagem com a nossa "chave secreta".
    Mensagem essa que contém os dados do seu usuário e/ou demais dados que você
    quiser colocar dentro de "data".
    O resultado dessa função é o token criptografado. */
    const token = jwt.sign({ data: { userId: user.id } }, secret, jwtConfig);

    res.status(200).json({ token });
  } catch (err) {
    return res
      .status(500)
      .json({ message: 'Erro interno', error: err.message });
  }
};
