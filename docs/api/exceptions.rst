promptguard.exceptions
======================

All exceptions inherit from :class:`~promptguard.PromptGuardError` so you can
catch the entire hierarchy with a single ``except`` clause.

.. code-block:: python

   from promptguard.exceptions import PromptGuardError

   try:
       result = guard.analyze(prompt)
   except PromptGuardError as e:
       print(f"PromptGuard error: {e}")

.. autoclass:: promptguard.PromptGuardError

.. autoclass:: promptguard.ModelLoadError

.. autoclass:: promptguard.ValidationError

.. autoclass:: promptguard.ConfigurationError

.. autoclass:: promptguard.InferenceError
