# Copyright (c) 2014 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import contextlib
import weakref

#from neutron_lib.db import utils as db_utils
from networking_ovn.neutron_lib.db import utils as db_utils
from oslo_db.sqlalchemy import utils as sa_utils
from oslo_log import log as logging
from oslo_utils import excutils
import six
from sqlalchemy import and_
from sqlalchemy.ext import associationproxy
from sqlalchemy import or_
from sqlalchemy import sql

#from neutron._i18n import _LE
from networking_ovn._i18n import _LE
from neutron.api.v2 import attributes


LOG = logging.getLogger(__name__)


@contextlib.contextmanager
def _noop_context_manager():
    yield


def safe_creation(context, create_fn, delete_fn, create_bindings,
                  transaction=True):
    '''This function wraps logic of object creation in safe atomic way.

    In case of exception, object is deleted.

    More information when this method could be used can be found in
    developer guide - Effective Neutron: Database interaction section.
    http://docs.openstack.org/developer/neutron/devref/effective_neutron.html

    :param context: context

    :param create_fn: function without arguments that is called to create
        object and returns this object.

    :param delete_fn: function that is called to delete an object. It is
        called with object's id field as an argument.

    :param create_bindings: function that is called to create bindings for
        an object. It is called with object's id field as an argument.

    :param transaction: if true the whole operation will be wrapped in a
        transaction. if false, no transaction will be used.
    '''
    cm = (context.session.begin(subtransactions=True)
          if transaction else _noop_context_manager())
    with cm:
        obj = create_fn()
        try:
            value = create_bindings(obj['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                try:
                    delete_fn(obj['id'])
                except Exception as e:
                    LOG.error(_LE("Cannot clean up created object %(obj)s. "
                                  "Exception: %(exc)s"), {'obj': obj['id'],
                                                          'exc': e})
        return obj, value


def model_query_scope(context, model):
    # Unless a context has 'admin' or 'advanced-service' rights the
    # query will be scoped to a single tenant_id
    return ((not context.is_admin and hasattr(model, 'tenant_id')) and
            (not context.is_advsvc and hasattr(model, 'tenant_id')))


def model_query(context, model):
    query = context.session.query(model)
    # define basic filter condition for model query
    query_filter = None
    if model_query_scope(context, model):
        query_filter = (model.tenant_id == context.tenant_id)

    if query_filter is not None:
        query = query.filter(query_filter)
    return query


class CommonDbMixin(object):
    """Common methods used in core and service plugins."""
    # Plugins, mixin classes implementing extension will register
    # hooks into the dict below for "augmenting" the "core way" of
    # building a query for retrieving objects from a model class.
    # To this aim, the register_model_query_hook and unregister_query_hook
    # from this class should be invoked
    _model_query_hooks = {}

    # This dictionary will store methods for extending attributes of
    # api resources. Mixins can use this dict for adding their own methods
    # TODO(salvatore-orlando): Avoid using class-level variables
    _dict_extend_functions = {}

    @classmethod
    def register_model_query_hook(cls, model, name, query_hook, filter_hook,
                                  result_filters=None):
        """Register a hook to be invoked when a query is executed.

        Add the hooks to the _model_query_hooks dict. Models are the keys
        of this dict, whereas the value is another dict mapping hook names to
        callables performing the hook.
        Each hook has a "query" component, used to build the query expression
        and a "filter" component, which is used to build the filter expression.

        Query hooks take as input the query being built and return a
        transformed query expression.

        Filter hooks take as input the filter expression being built and return
        a transformed filter expression
        """
        cls._model_query_hooks.setdefault(model, {})[name] = {
            'query': query_hook, 'filter': filter_hook,
            'result_filters': result_filters}

    @classmethod
    def register_dict_extend_funcs(cls, resource, funcs):
        cls._dict_extend_functions.setdefault(resource, []).extend(funcs)

    @property
    def safe_reference(self):
        """Return a weakref to the instance.

        Minimize the potential for the instance persisting
        unnecessarily in memory by returning a weakref proxy that
        won't prevent deallocation.
        """
        return weakref.proxy(self)

    def model_query_scope(self, context, model):
        return model_query_scope(context, model)

    def _model_query(self, context, model):
        query = context.session.query(model)
        # define basic filter condition for model query
        query_filter = None
        if self.model_query_scope(context, model):
            if hasattr(model, 'rbac_entries'):
                query = query.outerjoin(model.rbac_entries)
                rbac_model = model.rbac_entries.property.mapper.class_
                query_filter = (
                    (model.tenant_id == context.tenant_id) |
                    ((rbac_model.action == 'access_as_shared') &
                     ((rbac_model.target_tenant == context.tenant_id) |
                      (rbac_model.target_tenant == '*'))))
            elif hasattr(model, 'shared'):
                query_filter = ((model.tenant_id == context.tenant_id) |
                                (model.shared == sql.true()))
            else:
                query_filter = (model.tenant_id == context.tenant_id)
        # Execute query hooks registered from mixins and plugins
        for _name, hooks in six.iteritems(self._model_query_hooks.get(model,
                                                                      {})):
            query_hook = hooks.get('query')
            if isinstance(query_hook, six.string_types):
                query_hook = getattr(self, query_hook, None)
            if query_hook:
                query = query_hook(context, model, query)

            filter_hook = hooks.get('filter')
            if isinstance(filter_hook, six.string_types):
                filter_hook = getattr(self, filter_hook, None)
            if filter_hook:
                query_filter = filter_hook(context, model, query_filter)

        # NOTE(salvatore-orlando): 'if query_filter' will try to evaluate the
        # condition, raising an exception
        if query_filter is not None:
            query = query.filter(query_filter)
        return query

    def _fields(self, resource, fields):
        if fields:
            resource = {key: item for key, item in resource.items()
                        if key in fields}
        return attributes.populate_project_info(resource)

    def _get_by_id(self, context, model, id):
        query = self._model_query(context, model)
        return query.filter(model.id == id).one()

    def _apply_filters_to_query(self, query, model, filters, context=None):
        if filters:
            for key, value in six.iteritems(filters):
                column = getattr(model, key, None)
                # NOTE(kevinbenton): if column is a hybrid property that
                # references another expression, attempting to convert to
                # a boolean will fail so we must compare to None.
                # See "An Important Expression Language Gotcha" in:
                # docs.sqlalchemy.org/en/rel_0_9/changelog/migration_06.html
                if column is not None:
                    if not value:
                        query = query.filter(sql.false())
                        return query
                    if isinstance(column, associationproxy.AssociationProxy):
                        # association proxies don't support in_ so we have to
                        # do multiple equals matches
                        query = query.filter(
                            or_(*[column == v for v in value]))
                    else:
                        query = query.filter(column.in_(value))
                elif key == 'shared' and hasattr(model, 'rbac_entries'):
                    # translate a filter on shared into a query against the
                    # object's rbac entries
                    rbac = model.rbac_entries.property.mapper.class_
                    matches = [rbac.target_tenant == '*']
                    if context:
                        matches.append(rbac.target_tenant == context.tenant_id)
                    # any 'access_as_shared' records that match the
                    # wildcard or requesting tenant
                    is_shared = and_(rbac.action == 'access_as_shared',
                                     or_(*matches))
                    if not value[0]:
                        # NOTE(kevinbenton): we need to find objects that don't
                        # have an entry that matches the criteria above so
                        # we use a subquery to exclude them.
                        # We can't just filter the inverse of the query above
                        # because that will still give us a network shared to
                        # our tenant (or wildcard) if it's shared to another
                        # tenant.
                        # This is the column joining the table to rbac via
                        # the object_id. We can't just use model.id because
                        # subnets join on network.id so we have to inspect the
                        # relationship.
                        join_cols = model.rbac_entries.property.local_columns
                        oid_col = list(join_cols)[0]
                        is_shared = ~oid_col.in_(
                            query.session.query(rbac.object_id).
                            filter(is_shared)
                        )
                    elif (not context or
                          not self.model_query_scope(context, model)):
                        # we only want to join if we aren't using the subquery
                        # and if we aren't already joined because this is a
                        # scoped query
                        query = query.outerjoin(model.rbac_entries)
                    query = query.filter(is_shared)
            for _nam, hooks in six.iteritems(self._model_query_hooks.get(model,
                                                                         {})):
                result_filter = hooks.get('result_filters', None)
                if isinstance(result_filter, six.string_types):
                    result_filter = getattr(self, result_filter, None)

                if result_filter:
                    query = result_filter(query, filters)
        return query

    def _apply_dict_extend_functions(self, resource_type,
                                     response, db_object):
        for func in self._dict_extend_functions.get(
            resource_type, []):
            args = (response, db_object)
            if isinstance(func, six.string_types):
                func = getattr(self, func, None)
            else:
                # must call unbound method - use self as 1st argument
                args = (self,) + args
            if func:
                func(*args)

    def _get_collection_query(self, context, model, filters=None,
                              sorts=None, limit=None, marker_obj=None,
                              page_reverse=False):
        collection = self._model_query(context, model)
        collection = self._apply_filters_to_query(collection, model, filters,
                                                  context)
        if sorts:
            sort_keys = db_utils.get_and_validate_sort_keys(sorts, model)
            sort_dirs = db_utils.get_sort_dirs(sorts, page_reverse)
            # we always want deterministic results for sorted queries
            # so add unique keys to limit queries when present.
            # (http://docs.sqlalchemy.org/en/latest/orm/
            #  loading_relationships.html#subqueryload-ordering)
            # (http://docs.sqlalchemy.org/en/latest/faq/
            #  ormconfiguration.html#faq-subqueryload-limit-sort)
            for k in self._unique_keys(model, marker_obj):
                if k not in sort_keys:
                    sort_keys.append(k)
                    sort_dirs.append('asc')
            collection = sa_utils.paginate_query(collection, model, limit,
                                                 marker=marker_obj,
                                                 sort_keys=sort_keys,
                                                 sort_dirs=sort_dirs)
        return collection

    def _unique_keys(self, model, marker_obj):
        # just grab first set of unique keys and use them.
        # if model has no unqiue sets, 'paginate_query' will
        # warn if sorting is unstable
        uk_sets = sa_utils._get_unique_keys(model)
        for kset in uk_sets:
            for k in kset:
                if marker_obj and isinstance(getattr(marker_obj, k), bool):
                    # TODO(kevinbenton): workaround for bug/1656947.
                    # we can't use boolean cols until that bug is fixed. return
                    # first entry in uk_sets once that bug is resolved
                    break
            else:
                return kset
        return []

    def _get_collection(self, context, model, dict_func, filters=None,
                        fields=None, sorts=None, limit=None, marker_obj=None,
                        page_reverse=False):
        query = self._get_collection_query(context, model, filters=filters,
                                           sorts=sorts,
                                           limit=limit,
                                           marker_obj=marker_obj,
                                           page_reverse=page_reverse)
        items = [attributes.populate_project_info(dict_func(c, fields))
                 for c in query]
        if limit and page_reverse:
            items.reverse()
        return items

    def _get_collection_count(self, context, model, filters=None):
        return self._get_collection_query(context, model, filters).count()

    def _get_marker_obj(self, context, resource, limit, marker):
        if limit and marker:
            return getattr(self, '_get_%s' % resource)(context, marker)
        return None

    def _filter_non_model_columns(self, data, model):
        """Remove all the attributes from data which are not columns or
        association proxies of the model passed as second parameter
        """
        columns = [c.name for c in model.__table__.columns]
        return dict((k, v) for (k, v) in
                    six.iteritems(data) if k in columns or
                    isinstance(getattr(model, k, None),
                               associationproxy.AssociationProxy))
